rule TTP_XOR_WriteProcessMemory_99fc {
  strings:
    $key_99fc = { ce 8e [2] fc ac [2] fa 99 [2] d4 99 [2] eb 85 }

  condition:
    any of them
}