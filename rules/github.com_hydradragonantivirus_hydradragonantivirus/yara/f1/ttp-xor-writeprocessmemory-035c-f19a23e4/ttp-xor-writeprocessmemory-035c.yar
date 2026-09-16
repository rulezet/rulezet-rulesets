rule TTP_XOR_WriteProcessMemory_035c {
  strings:
    $key_035c = { 54 2e [2] 66 0c [2] 60 39 [2] 4e 39 [2] 71 25 }

  condition:
    any of them
}