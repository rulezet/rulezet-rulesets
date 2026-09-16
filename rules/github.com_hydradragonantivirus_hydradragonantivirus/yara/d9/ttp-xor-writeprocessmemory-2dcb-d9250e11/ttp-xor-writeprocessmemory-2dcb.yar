rule TTP_XOR_WriteProcessMemory_2dcb {
  strings:
    $key_2dcb = { 7a b9 [2] 48 9b [2] 4e ae [2] 60 ae [2] 5f b2 }

  condition:
    any of them
}