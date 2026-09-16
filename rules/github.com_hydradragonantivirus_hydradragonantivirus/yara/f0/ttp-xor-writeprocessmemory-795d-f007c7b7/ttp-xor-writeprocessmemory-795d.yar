rule TTP_XOR_WriteProcessMemory_795d {
  strings:
    $key_795d = { 2e 2f [2] 1c 0d [2] 1a 38 [2] 34 38 [2] 0b 24 }

  condition:
    any of them
}