rule TTP_XOR_WriteProcessMemory_ffea {
  strings:
    $key_ffea = { a8 98 [2] 9a ba [2] 9c 8f [2] b2 8f [2] 8d 93 }

  condition:
    any of them
}