rule TTP_XOR_WriteProcessMemory_7056 {
  strings:
    $key_7056 = { 27 24 [2] 15 06 [2] 13 33 [2] 3d 33 [2] 02 2f }

  condition:
    any of them
}