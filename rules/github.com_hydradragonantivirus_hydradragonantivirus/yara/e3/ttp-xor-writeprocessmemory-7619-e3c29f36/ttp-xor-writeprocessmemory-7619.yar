rule TTP_XOR_WriteProcessMemory_7619 {
  strings:
    $key_7619 = { 21 6b [2] 13 49 [2] 15 7c [2] 3b 7c [2] 04 60 }

  condition:
    any of them
}