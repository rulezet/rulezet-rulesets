rule TTP_XOR_WriteProcessMemory_335c {
  strings:
    $key_335c = { 64 2e [2] 56 0c [2] 50 39 [2] 7e 39 [2] 41 25 }

  condition:
    any of them
}