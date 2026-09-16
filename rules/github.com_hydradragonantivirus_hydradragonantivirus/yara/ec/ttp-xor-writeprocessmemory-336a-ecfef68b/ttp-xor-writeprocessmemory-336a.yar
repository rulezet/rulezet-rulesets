rule TTP_XOR_WriteProcessMemory_336a {
  strings:
    $key_336a = { 64 18 [2] 56 3a [2] 50 0f [2] 7e 0f [2] 41 13 }

  condition:
    any of them
}