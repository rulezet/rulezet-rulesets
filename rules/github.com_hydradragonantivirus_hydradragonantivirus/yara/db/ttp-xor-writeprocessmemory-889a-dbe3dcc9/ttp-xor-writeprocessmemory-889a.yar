rule TTP_XOR_WriteProcessMemory_889a {
  strings:
    $key_889a = { df e8 [2] ed ca [2] eb ff [2] c5 ff [2] fa e3 }

  condition:
    any of them
}