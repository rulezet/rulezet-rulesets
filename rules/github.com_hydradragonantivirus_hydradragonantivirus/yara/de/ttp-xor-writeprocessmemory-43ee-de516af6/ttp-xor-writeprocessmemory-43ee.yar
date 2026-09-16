rule TTP_XOR_WriteProcessMemory_43ee {
  strings:
    $key_43ee = { 14 9c [2] 26 be [2] 20 8b [2] 0e 8b [2] 31 97 }

  condition:
    any of them
}