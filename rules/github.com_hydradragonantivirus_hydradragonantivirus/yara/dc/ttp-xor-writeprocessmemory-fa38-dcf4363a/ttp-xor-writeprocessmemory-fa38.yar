rule TTP_XOR_WriteProcessMemory_fa38 {
  strings:
    $key_fa38 = { ad 4a [2] 9f 68 [2] 99 5d [2] b7 5d [2] 88 41 }

  condition:
    any of them
}