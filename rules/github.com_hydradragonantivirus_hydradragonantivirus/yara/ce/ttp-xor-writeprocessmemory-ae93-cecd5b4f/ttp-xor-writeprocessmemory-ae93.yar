rule TTP_XOR_WriteProcessMemory_ae93 {
  strings:
    $key_ae93 = { f9 e1 [2] cb c3 [2] cd f6 [2] e3 f6 [2] dc ea }

  condition:
    any of them
}