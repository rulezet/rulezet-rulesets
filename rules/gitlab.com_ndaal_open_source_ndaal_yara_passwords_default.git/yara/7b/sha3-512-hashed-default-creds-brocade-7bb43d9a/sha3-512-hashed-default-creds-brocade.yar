rule sha3_512_hashed_default_creds_brocade
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for brocade."
        category = "INFO"
        info = "SHA3_512"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="1dd4032a2e92f759da53faa09dd47997e146557dbd973b66ffae88d2c579768afb2027fdae1b1cf158a77931104f95098cc92febc544c4aa2ef9253262b8d541"
    $a1="ad0c9f9157129a815aa678c8464c440984c1ff2751ad4fe751af01b647e4213e75e8f1a9bc1a3b04bb5b97ba20617754131ff8accac33ff822a7fb05e92410df"
    $a2="c1eb5876a443af248e9c003ecd7004daf84a41dc11e1a0dcbaa6639f053d27432464771a853e856c20aae5bc04aeb66dabc5872897c1ffb1a17e6d895c529ff7"
    $a3="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a4="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a5="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a6="e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716"
    $a7="dee4164777a98291e138fcebcf7ea59a837226bc8388cd1cf694581586910a81d46f07b93c068f17eae5a8337201af7d51b3a888a6db41915d801cb15b6058e5"
    $a8="23051c691d244f4355f15b68b586fbc4b7db676b3e545a779181511f515173e3393a17bb1768871291e450bb82a8c7bcf236b485999e5f5168cd96bfd1a014be"
    $a9="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
    $a10="5da9b88d9fce0f291bb02e5c0cf1ddce000483486a1c609bb1a004907c9e4a8518e327cd9686c92e59d02b1dfe1ca315474f7fc218c95d66d6d7f00a979e48e3"
    $a11="5a38afb1a18d408e6cd367f9db91e2ab9bce834cdad3da24183cc174956c20ce35dd39c2bd36aae907111ae3d6ada353f7697a5f1a8fc567aae9e4ca41a9d19d"
    $a12="d0321f34513743e2a1a61be5298c2e3775c1d12fba3ed5fff8109e131b534f84e28b14b38a5123fa1026b91ba5e5ab4fc4719f1db4267db302e76f1999de8aee"
    $a13="8cd824c700eb0c125fff40c8c185d14c5dfe7f32814afac079ba7c20d93bc3c082193243c420fed22ef2474fbb85880e7bc1ca772150a1f759f8ddebca77711f"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}