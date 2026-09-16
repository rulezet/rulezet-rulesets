rule TTP_XOR_WriteProcessMemory_14ea {
  strings:
    $key_14ea = { 43 98 [2] 71 ba [2] 77 8f [2] 59 8f [2] 66 93 }

  condition:
    any of them
}