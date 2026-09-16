rule TTP_XOR_WriteProcessMemory_cfcb {
  strings:
    $key_cfcb = { 98 b9 [2] aa 9b [2] ac ae [2] 82 ae [2] bd b2 }

  condition:
    any of them
}