rule TTP_XOR_WriteProcessMemory_dcdf {
  strings:
    $key_dcdf = { 8b ad [2] b9 8f [2] bf ba [2] 91 ba [2] ae a6 }

  condition:
    any of them
}