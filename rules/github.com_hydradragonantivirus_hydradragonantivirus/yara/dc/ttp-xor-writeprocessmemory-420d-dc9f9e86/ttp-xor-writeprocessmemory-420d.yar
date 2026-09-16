rule TTP_XOR_WriteProcessMemory_420d {
  strings:
    $key_420d = { 15 7f [2] 27 5d [2] 21 68 [2] 0f 68 [2] 30 74 }

  condition:
    any of them
}