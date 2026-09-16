import "pe"
rule _Trojan_Autorun_Trojan_GenericKD_72517131_93_1_Trojan_Autorun_Tr_12 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72517131_93_1.vir, Trojan.Autorun_Trojan.GenericKD.73131881_1.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6a357e523ed6bb8fbd373578de488ebe39e700186f4f4ed8a7092be6b13593a"
    hash2       = "dd18c3e61e9b6ecd58a6c4197727ed9fa3520cf7aa34db53cf4bdbacdd3d8858"
    hash3       = "bd6ef55c97c4e362cb909205f130485768fa8aeb0ef4c8bdb812c4744b15ef1d"

  strings:
    $s1  = "Unhandled exception in DeeplinkMusicPlayToCommand::OnExecute" fullword wide
    $s2  = "Unhandled exception in PlayAllCommand::OnExecute's playback task" fullword wide
    $s3  = "Unhandled exception in PlayAllCommand::OnExecute" fullword wide
    $s4  = "Executing PlayTo command" fullword wide
    $s5  = " - assert(!L\"Attempt to restart track with null context\") failed" fullword wide
    $s6  = " - assert(!L\"Attempt to add null album object\") failed" fullword wide
    $s7  = " - assert(!L\"Attempt to add null artist object\") failed" fullword wide
    $s8  = " - assert(!L\"VectorOperation handler not implemented\") failed" fullword wide
    $s9  = "Skipping logging media usage error for {0}" fullword wide
    $s10 = "!!! Unknown SystemMediaTransportControlsButton value !!!" fullword wide
    $s11 = "local file - getting stream & setting media binder stream source" fullword wide
    $s12 = " - assert(CurrentlyOnBackgroundThread()) failed" fullword wide
    $s13 = " - assert(!IsBackgroundThread()) failed" fullword wide
    $s14 = "Processing PlayTo item with title [{0}], description [{1}]" fullword wide
    $s15 = " - assert(IsUIThreadForCurrentWindow()) failed" fullword wide
    $s16 = " - assert(m_viewModel != nullptr && m_scrubberSlider != nullptr) failed" fullword wide
    $s17 = "Failed to create async operation in GetStoreAlbumDetailsTask()" fullword wide
    $s18 = " - Warning: Condition (!L\"Restored shuffled queue, but our persisted shuffle value was false.  These values should be in sync." wide
    $s19 = " - Warning: Condition (TestEnumFlags(outDetails.populatedFields, fields)) failed" fullword wide
    $s20 = "Platform.?$WriteOnlyArray@P$AAUIHasCatalogDataCommandItemDetails@Framework@Entertainment@MS@@$00" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "3235d0a66c0a8ca4d8b84f3bea439dce" and (8 of them)
    ) or (all of them)
}