rule TTP_XOR_WriteProcessMemory_89da {
  strings:
    $key_89da = { de a8 [2] ec 8a [2] ea bf [2] c4 bf [2] fb a3 }

  condition:
    any of them
}