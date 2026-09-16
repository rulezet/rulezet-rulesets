rule TTP_XOR_WriteProcessMemory_f2ba {
  strings:
    $key_f2ba = { a5 c8 [2] 97 ea [2] 91 df [2] bf df [2] 80 c3 }

  condition:
    any of them
}