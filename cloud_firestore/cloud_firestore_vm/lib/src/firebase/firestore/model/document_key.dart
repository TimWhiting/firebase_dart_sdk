// File created by
// Lung Razvan <long1eu>
// on 17/09/2018
import 'package:_firebase_database_collection_vm/_firebase_database_collection_vm.dart';
import 'package:_firebase_internal_vm/_firebase_internal_vm.dart';
import 'package:cloud_firestore_vm/src/firebase/firestore/model/resource_path.dart';
import 'package:cloud_firestore_vm/src/firebase/firestore/util/assert.dart';

/// DocumentKey represents the location of a document in the Firestore database.
class DocumentKey implements Comparable<DocumentKey> {
  DocumentKey._(this.path) {
    hardAssert(isDocumentKey(path), 'Not a document key path: $path');
  }

  /// Returns a document key for the empty path.
  factory DocumentKey.empty() => DocumentKey._(ResourcePath.empty);

  /// Creates and returns a new document key with the given path.
  factory DocumentKey.fromPath(ResourcePath path) => DocumentKey._(path);

  /// Creates and returns a new document key with the given segments.
  factory DocumentKey.fromSegments(List<String> segments) {
    return DocumentKey._(ResourcePath.fromSegments(segments));
  }

  /// Creates and returns a new document key using '/' to split the string into segments.
  factory DocumentKey.fromPathString(String path) {
    return DocumentKey._(ResourcePath.fromString(path));
  }

  static const String keyFieldName = '__name__';

  /// The path to the document.
  final ResourcePath path;

  /// Returns true if the document is in the specified collectionId.
  bool hasCollectionId(String collectionId) {
    return path.length >= 2 && path.segments[path.length - 2] == collectionId;
  }

  static int comparator(DocumentKey a, DocumentKey b) =>
      a.path.compareTo(b.path);

  static final ImmutableSortedSet<DocumentKey> emptyKeySet =
      ImmutableSortedSet<DocumentKey>();

  /// Returns true iff the given path is a path to a document.
  static bool isDocumentKey(ResourcePath path) => path.length.remainder(2) == 0;

  /// Returns true iff the given path is a path to a document.
  @override
  int compareTo(DocumentKey other) {
    if (other == null) {
      return 1;
    }
    return path.compareTo(other.path);
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is DocumentKey &&
          runtimeType == other.runtimeType &&
          path == other.path;

  @override
  int get hashCode => path.hashCode;

  @override
  String toString() {
    return (ToStringHelper(runtimeType)..add('path', path)).toString();
  }
}
