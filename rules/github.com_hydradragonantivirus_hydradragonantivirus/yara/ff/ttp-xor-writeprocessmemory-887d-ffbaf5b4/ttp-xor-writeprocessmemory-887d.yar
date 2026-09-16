rule TTP_XOR_WriteProcessMemory_887d {
  strings:
    $key_887d = { df 0f [2] ed 2d [2] eb 18 [2] c5 18 [2] fa 04 }

  condition:
    any of them
}