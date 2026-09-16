rule TTP_XOR_WriteProcessMemory_8ddb {
  strings:
    $key_8ddb = { da a9 [2] e8 8b [2] ee be [2] c0 be [2] ff a2 }

  condition:
    any of them
}