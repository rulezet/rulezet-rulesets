rule TTP_XOR_WriteProcessMemory_99fb {
  strings:
    $key_99fb = { ce 89 [2] fc ab [2] fa 9e [2] d4 9e [2] eb 82 }

  condition:
    any of them
}