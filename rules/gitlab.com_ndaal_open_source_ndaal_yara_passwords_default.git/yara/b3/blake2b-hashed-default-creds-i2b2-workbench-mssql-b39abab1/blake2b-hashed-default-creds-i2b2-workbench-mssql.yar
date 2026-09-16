rule blake2b_hashed_default_creds_i2b2_workbench_mssql
{
    meta:
        version = "1.0"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "NDAAL GESELLSCHAFT FÜR SICHERHEIT INDER INFORMATIONSTECHNIK MBH & CO KG"
        author = "Alaa Jubakhanji@ndaal Gesellschaft fürSicherheit in der Informationstechnik mbH & Co KG"
        description = "Hashed values of default credentials for i2b2_workbench_mssql."
        category = "INFO"
        info = "BLAKE2B"
        reference = "https://gitlab.com/ndaal_open_source/ndaal_yara_passwords_default/-/tree/main/yara_rules"

strings:
    $a0="2ef960d5594ac71c239abf7c16ff171fbd72544a30e651af0f1cd4ce232aab67f7438d8e4b3c8f71d4d7ebc5a920c13cd7b091d4666d7c0bf3799fecf1c22d71"
    $a1="3c19678a1c283c8ff312206654b29709731ae3479f94dabd32e72f5229c8e4ecfd382b69511c54b922f446cb4947ed4a81f8feefce33ee7270493579301db32f"
    $a2="17906556916c067fb12714440b640f2910439bbb5ad33df1f7b7795f7d8f29b4dc99cbb186dc2873690cefa9cf144447fe5d15c7e86e34612a9f4231a45adb81"
    $a3="103a5f5e1e65885b0f4f4efdd21a5c3946adc273c35c094d883ac39a8d4558af307cdccac070625f5dbd99a621000c6a72824fe36f18b89a235ed8937e6beb4d"
    $a4="99600ea71c95fc3dc8f1af0f00d9a548fd832a9e72184450c970b56f0a33ac6364d641b4ca5d6cbe7c13a3084468df5a393c07e376cca0257aa761f7d32ad43f"
    $a5="63efc6c2971af6dd669cac7cea02a482540c5aabd76bd9ed46c15ce9db59cd240d9e01410b9bd32a53d22b6f03d6afa3b98b1315cba5617b4a8d6619fca4b110"
    $a6="538bb983e427de025c29a6328c9016ff47d08ca1078e108ae19ff6075b1675a24ab30fa566f155dd97f097bd3db3f29f17d09ef4ca2c4166f60e009afe66f334"
    $a7="379b43981b4a753bc61cf2cb68d2cc2227f6512c0722b3564b6e4d7e9634450ae7d85fb8f36afcf93dbac676e92a5b19098acb665f6f0fe60c7ef52d4d9af122"
    $a8="b4ac6e50c8bfe95c3d30f126fc810bff485f5de02c5bd5dd75d7b7e41241bd7a973dbc2d25ba99297cc45c0bcd64561a557954a890b7a895e2416eebf62b6c0b"
    $a9="18b503de6a17acd2e91d0192beb0da7d66b5e0b4a26f69c25049db88cc15545d7d2bfc71005773de1a2642a64795145df9d58e036abd1f2e523ea75e9fa768ce"
    $a10="3f32fda7814cc94a814e4e336e63749be8d087da1852676a2d0a31dc6c4c7c289fc52e8762030abd3dad6482572cc7f67319c21723033ac0f8b5b06f525cc210"
    $a11="fadc0cd4ea62e7b7e7125900d36cc8f7e3855c1ca4d54415658daf17b14968550bc875af8c2224456995b84d21912ba356153cea5977806e356aec140207437d"
    $a12="837e01334b036ce17939f3aa51433f6b06b7b9079ce737e12550332cdf36fb16673fa7da7daecde7acc08017f204fe73df690009757734f4f68162c739765585"
    $a13="b3f3f60624f6a64ae639a257fb46a6c5b94e6c15951800087e377f78b2a565d62d9d0c0f713eeda51ecd7ac676a463803c4c73c808fb34a1ccda8d5016ccc90d"
condition:
    ($a0 and $a1) or ($a2 and $a3) or ($a4 and $a5) or ($a6 and $a7) or ($a8 and $a9) or ($a10 and $a11) or ($a12 and $a13)
}