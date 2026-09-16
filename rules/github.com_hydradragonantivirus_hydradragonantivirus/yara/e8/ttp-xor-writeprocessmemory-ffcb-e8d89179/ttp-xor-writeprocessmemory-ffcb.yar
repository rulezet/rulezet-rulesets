rule TTP_XOR_WriteProcessMemory_ffcb {
  strings:
    $key_ffcb = { a8 b9 [2] 9a 9b [2] 9c ae [2] b2 ae [2] 8d b2 }

  condition:
    any of them
}