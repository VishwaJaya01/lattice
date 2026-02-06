----------------------------- MODULE LatticeShardRecovery -----------------------------
EXTENDS Naturals, Sequences, FiniteSets, TLC

(***************************************************************************)
(* Lattice sharding + recovery model.                                      *)
(*                                                                         *)
(* - Pref models the deterministic consistent-hash worker preference order *)
(*   for each batch key.                                                   *)
(* - Fail/Recover update live membership.                                  *)
(* - In-flight batches are always (re)owned by PickLive over current live *)
(*   members, or NONE when no workers are live.                            *)
(***************************************************************************)

CONSTANTS Workers, Batches

None == "NONE"

SeqToSet(seq) == {seq[i] : i \in 1..Len(seq)}

NoDup(seq) ==
  \A i, j \in 1..Len(seq): i # j => seq[i] # seq[j]

IsPermutation(seq, s) ==
  /\ Len(seq) = Cardinality(s)
  /\ SeqToSet(seq) = s
  /\ NoDup(seq)

PermutationsOf(s) ==
  {p \in [1..Cardinality(s) -> s] : IsPermutation(p, s)}

Pref ==
  [b \in Batches |-> CHOOSE p \in PermutationsOf(Workers): TRUE]

MinElem(s) ==
  CHOOSE i \in s: \A j \in s: i <= j

ASSUME
  /\ Workers # {}
  /\ Batches # {}

PickLive(b, liveSet) ==
  LET idxs == {i \in 1..Len(Pref[b]) : Pref[b][i] \in liveSet}
  IN IF idxs = {} THEN None ELSE Pref[b][MinElem(idxs)]

VARIABLES live, accepted, rejected, inflight, completed, owner

vars == <<live, accepted, rejected, inflight, completed, owner>>

TypeOK ==
  /\ live \subseteq Workers
  /\ accepted \subseteq Batches
  /\ rejected \subseteq Batches
  /\ inflight \subseteq Batches
  /\ completed \subseteq Batches
  /\ owner \in [Batches -> Workers \cup {None}]

Init ==
  /\ live = Workers
  /\ accepted = {}
  /\ rejected = {}
  /\ inflight = {}
  /\ completed = {}
  /\ owner = [b \in Batches |-> None]

SubmitAccepted(b) ==
  /\ b \in Batches \ (accepted \cup rejected)
  /\ live # {}
  /\ accepted' = accepted \cup {b}
  /\ inflight' = inflight \cup {b}
  /\ completed' = completed
  /\ rejected' = rejected
  /\ owner' = [owner EXCEPT ![b] = PickLive(b, live)]
  /\ UNCHANGED live

SubmitRejected(b) ==
  /\ b \in Batches \ (accepted \cup rejected)
  /\ live = {}
  /\ rejected' = rejected \cup {b}
  /\ UNCHANGED <<live, accepted, inflight, completed, owner>>

Complete(b) ==
  /\ b \in inflight
  /\ owner[b] # None
  /\ owner[b] \in live
  /\ inflight' = inflight \ {b}
  /\ completed' = completed \cup {b}
  /\ owner' = [owner EXCEPT ![b] = None]
  /\ UNCHANGED <<live, accepted, rejected>>

Fail(w) ==
  /\ w \in live
  /\ LET newLive == live \ {w}
     IN
       /\ live' = newLive
       /\ owner' =
            [b \in Batches |->
               IF b \in inflight
               THEN PickLive(b, newLive)
               ELSE owner[b]]
  /\ UNCHANGED <<accepted, rejected, inflight, completed>>

Recover(w) ==
  /\ w \in Workers \ live
  /\ LET newLive == live \cup {w}
     IN
       /\ live' = newLive
       /\ owner' =
            [b \in Batches |->
               IF b \in inflight
               THEN PickLive(b, newLive)
               ELSE owner[b]]
  /\ UNCHANGED <<accepted, rejected, inflight, completed>>

Next ==
  \/ \E b \in Batches: SubmitAccepted(b)
  \/ \E b \in Batches: SubmitRejected(b)
  \/ \E b \in Batches: Complete(b)
  \/ \E w \in Workers: Fail(w)
  \/ \E w \in Workers: Recover(w)

Spec == Init /\ [][Next]_vars

\* Safety properties checked by TLC.
AcceptedAccounted == accepted = inflight \cup completed

NoRejectedAccepted == (accepted \cap rejected) = {}

DisjointInflightCompleted == inflight \cap completed = {}

InflightOwnedWhenPossible ==
  \A b \in inflight:
    IF live = {}
    THEN owner[b] = None
    ELSE owner[b] \in live

OwnerMatchesHash ==
  \A b \in inflight: owner[b] = PickLive(b, live)

NoCompletedRegression ==
  \A b \in completed: owner[b] = None

=============================================================================
