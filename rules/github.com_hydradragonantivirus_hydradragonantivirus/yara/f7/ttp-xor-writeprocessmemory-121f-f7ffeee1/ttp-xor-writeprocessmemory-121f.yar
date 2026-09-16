rule TTP_XOR_WriteProcessMemory_121f {
  strings:
    $key_121f = { 45 6d [2] 77 4f [2] 71 7a [2] 5f 7a [2] 60 66 }

  condition:
    any of them
}