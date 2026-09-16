rule TTP_XOR_WriteProcessMemory_387d {
  strings:
    $key_387d = { 6f 0f [2] 5d 2d [2] 5b 18 [2] 75 18 [2] 4a 04 }

  condition:
    any of them
}