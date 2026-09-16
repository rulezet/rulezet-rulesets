rule TTP_XOR_WriteProcessMemory_2e1f {
  strings:
    $key_2e1f = { 79 6d [2] 4b 4f [2] 4d 7a [2] 63 7a [2] 5c 66 }

  condition:
    any of them
}