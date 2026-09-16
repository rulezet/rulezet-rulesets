rule TTP_XOR_WriteProcessMemory_fecb {
  strings:
    $key_fecb = { a9 b9 [2] 9b 9b [2] 9d ae [2] b3 ae [2] 8c b2 }

  condition:
    any of them
}