rule TTP_XOR_WriteProcessMemory_789c {
  strings:
    $key_789c = { 2f ee [2] 1d cc [2] 1b f9 [2] 35 f9 [2] 0a e5 }

  condition:
    any of them
}