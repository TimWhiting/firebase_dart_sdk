// File created by
// Lung Razvan <long1eu>
// on 02/10/2018

import 'dart:async';

import 'package:cloud_firestore_vm/src/firebase/firestore/local/memory/memory_persistence.dart';
import 'package:test/test.dart';

import 'cases/remote_document_cache_test_case.dart';
import 'persistence_test_helpers.dart';

void main() {
  RemoteDocumentCacheTestCase testCase;

  setUp(() async {
    print('setUp');
    final MemoryPersistence persistence =
        await createEagerGCMemoryPersistence();
    testCase = RemoteDocumentCacheTestCase(persistence)..setUp();
    print('setUpDone');
  });

  tearDown(() => Future<void>.delayed(
      const Duration(milliseconds: 250), () => testCase.tearDown()));

  test('testReadDocumentNotInCache',
      () => testCase.testReadDocumentNotInCache());
  test('testSetAndReadDocument', () => testCase.testSetAndReadDocument());
  test('testSetAndReadSeveralDocuments',
      () => testCase.testSetAndReadSeveralDocuments());
  test('testReadSeveralDocumentsIncludingMissingDocument',
      () => testCase.testReadSeveralDocumentsIncludingMissingDocument());
  test('testSetAndReadLotsOfDocuments',
      () => testCase.testSetAndReadLotsOfDocuments());
  test('testSetAndReadDeletedDocument',
      () => testCase.testSetAndReadDeletedDocument());
  test('testSetDocumentToNewValue', () => testCase.testSetDocumentToNewValue());
  test('testRemoveDocument', () => testCase.testRemoveDocument());
  test('testRemoveNonExistentDocument',
      () => testCase.testRemoveNonExistentDocument());
  test('testDocumentsMatchingQuery',
      () => testCase.testDocumentsMatchingQuery());
}
