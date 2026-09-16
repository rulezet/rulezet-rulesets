rule TTP_XOR_WriteProcessMemory_4b1f {
  strings:
    $key_4b1f = { 1c 6d [2] 2e 4f [2] 28 7a [2] 06 7a [2] 39 66 }

  condition:
    any of them
}