rule TTP_XOR_WriteProcessMemory_562f {
  strings:
    $key_562f = { 01 5d [2] 33 7f [2] 35 4a [2] 1b 4a [2] 24 56 }

  condition:
    any of them
}