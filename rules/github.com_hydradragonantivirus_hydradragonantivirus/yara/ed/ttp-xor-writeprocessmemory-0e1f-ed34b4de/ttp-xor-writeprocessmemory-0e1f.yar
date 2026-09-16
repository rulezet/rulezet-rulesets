rule TTP_XOR_WriteProcessMemory_0e1f {
  strings:
    $key_0e1f = { 59 6d [2] 6b 4f [2] 6d 7a [2] 43 7a [2] 7c 66 }

  condition:
    any of them
}