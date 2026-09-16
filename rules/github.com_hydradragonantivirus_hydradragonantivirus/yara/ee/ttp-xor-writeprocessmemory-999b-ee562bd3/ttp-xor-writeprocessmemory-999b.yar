rule TTP_XOR_WriteProcessMemory_999b {
  strings:
    $key_999b = { ce e9 [2] fc cb [2] fa fe [2] d4 fe [2] eb e2 }

  condition:
    any of them
}