rule TTP_XOR_WriteProcessMemory_384c {
  strings:
    $key_384c = { 6f 3e [2] 5d 1c [2] 5b 29 [2] 75 29 [2] 4a 35 }

  condition:
    any of them
}