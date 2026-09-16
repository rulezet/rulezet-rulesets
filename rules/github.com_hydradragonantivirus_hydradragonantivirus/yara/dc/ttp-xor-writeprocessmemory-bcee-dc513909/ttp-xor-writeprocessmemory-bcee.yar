rule TTP_XOR_WriteProcessMemory_bcee {
  strings:
    $key_bcee = { eb 9c [2] d9 be [2] df 8b [2] f1 8b [2] ce 97 }

  condition:
    any of them
}