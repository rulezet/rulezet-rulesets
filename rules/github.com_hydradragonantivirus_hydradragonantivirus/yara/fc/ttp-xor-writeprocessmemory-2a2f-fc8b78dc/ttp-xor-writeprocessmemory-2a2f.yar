rule TTP_XOR_WriteProcessMemory_2a2f {
  strings:
    $key_2a2f = { 7d 5d [2] 4f 7f [2] 49 4a [2] 67 4a [2] 58 56 }

  condition:
    any of them
}