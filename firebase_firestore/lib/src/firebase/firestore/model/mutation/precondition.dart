// File created by
// Lung Razvan <long1eu>
// on 17/09/2018

import 'package:firebase_firestore/src/firebase/firestore/model/document.dart';
import 'package:firebase_firestore/src/firebase/firestore/model/maybe_document.dart';
import 'package:firebase_firestore/src/firebase/firestore/model/snapshot_version.dart';
import 'package:firebase_firestore/src/firebase/firestore/no_document.dart';
import 'package:firebase_firestore/src/firebase/firestore/util/assert.dart';

/// Encodes a precondition for a mutation. This follows the model that
/// the backend accepts with the special case of an explicit "empty"
/// precondition (meaning no precondition).
class Precondition {
  static final Precondition none = Precondition(null, null);

  /// If set, preconditions a mutation based on the last updateTime.
  final SnapshotVersion updateTime;

  /// If set, preconditions a mutation based on whether the document exists.
  final bool exists;

  const Precondition(this.updateTime, this.exists)
      : assert(updateTime != null && exists != null,
            'Precondition can specify "exists" or "updateTime" but not both');

  /// Creates a new Precondition with an exists flag.
  factory Precondition.fromExists(bool exists) {
    return Precondition(null, exists);
  }

  /// Creates a new Precondition based on a version a document exists at.
  factory Precondition.fromUpdateTime(SnapshotVersion updateTime) {
    return Precondition(updateTime, null);
  }

  /// Returns whether this Precondition is empty.
  bool get isNone => updateTime == null && exists == null;

  /// Returns true if the preconditions is valid for the given document
  /// (or null if no document is available).
  bool isValidFor(MaybeDocument maybeDoc) {
    if (this.updateTime != null) {
      return maybeDoc is Document && maybeDoc.version == updateTime;
    } else if (exists != null) {
      if (exists) {
        return maybeDoc is Document;
      } else {
        return maybeDoc == null || maybeDoc is NoDocument;
      }
    } else {
      Assert.hardAssert(isNone, "Precondition should be empty");
      return true;
    }
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Precondition &&
          runtimeType == other.runtimeType &&
          updateTime == other.updateTime &&
          exists == other.exists;

  @override
  int get hashCode => updateTime.hashCode ^ exists.hashCode;

  @override
  String toString() {
    if (isNone) {
      return 'Precondition{<none>}';
    } else if (updateTime != null) {
      return 'Precondition{updateTime: $updateTime}';
    } else if (exists != null) {
      return 'Precondition{exists: $exists}';
    } else {
      throw Assert.fail('Invalid Precondition');
    }
  }
}
