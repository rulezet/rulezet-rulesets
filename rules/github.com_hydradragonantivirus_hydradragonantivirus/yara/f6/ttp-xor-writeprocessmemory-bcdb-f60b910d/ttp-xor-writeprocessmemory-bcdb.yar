rule TTP_XOR_WriteProcessMemory_bcdb {
  strings:
    $key_bcdb = { eb a9 [2] d9 8b [2] df be [2] f1 be [2] ce a2 }

  condition:
    any of them
}