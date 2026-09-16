rule TTP_XOR_WriteProcessMemory_146a {
  strings:
    $key_146a = { 43 18 [2] 71 3a [2] 77 0f [2] 59 0f [2] 66 13 }

  condition:
    any of them
}