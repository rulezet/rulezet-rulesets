rule TTP_XOR_WriteProcessMemory_164d {
  strings:
    $key_164d = { 41 3f [2] 73 1d [2] 75 28 [2] 5b 28 [2] 64 34 }

  condition:
    any of them
}