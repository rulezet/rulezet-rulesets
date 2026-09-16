rule TTP_XOR_WriteProcessMemory_664d {
  strings:
    $key_664d = { 31 3f [2] 03 1d [2] 05 28 [2] 2b 28 [2] 14 34 }

  condition:
    any of them
}