rule TTP_XOR_WriteProcessMemory_ce37 {
  strings:
    $key_ce37 = { 99 45 [2] ab 67 [2] ad 52 [2] 83 52 [2] bc 4e }

  condition:
    any of them
}