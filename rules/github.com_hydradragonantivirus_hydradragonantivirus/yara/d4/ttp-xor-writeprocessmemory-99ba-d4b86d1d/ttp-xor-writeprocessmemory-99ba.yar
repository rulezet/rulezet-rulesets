rule TTP_XOR_WriteProcessMemory_99ba {
  strings:
    $key_99ba = { ce c8 [2] fc ea [2] fa df [2] d4 df [2] eb c3 }

  condition:
    any of them
}