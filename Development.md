# Useful Links

https://learn.microsoft.com/en-us/windows/win32/direct3dhlsl/dx-graphics-hlsl-sm4-asm

https://learn.microsoft.com/en-us/windows/win32/direct3dhlsl/shader-model-5-assembly--directx-hlsl-

For DirectX ,they secretly hide a more deep documents here almost no one knows:
https://microsoft.github.io/DirectX-Specs/

And they hide old things in archive, which is more close to 3Dmigoto:
https://microsoft.github.io/DirectX-Specs/d3d/archive/D3D11_3_FunctionalSpec.htm

original repo:
https://github.com/microsoft/DirectX-Specs/tree/master

Dig Deeper:
https://github.com/microsoft/DirectXShaderCompiler


# Almost no documents for some thing like 'ld_indexable'

It seems it's just suddenly appear and be used everywhere but no one explain what it is.

almost everything is undocumented.

have to go everywhere on github to try find the clue.

And just find these:
https://github.com/spacehamster/DXDecompiler

the question is : why they stop update some thing like parse original binary code to hlsl?

then just find that :

dxilconv.dll, a DLL providing a converter from DXBC (older shader bytecode format)

in https://github.com/microsoft/DirectXShaderCompiler

now only DX11 use DXBC, DX12 prefer to use DXIL but compatible with DXBC(max to SM5.1).


# HLSL to DXBC, DXBC to HLSL, DXBC to DXIL to HLSL, HLSL to DXIL to DXBC

3dmigoto can parse DXBC to HLSL but not support for some features so always get a flawed HLSL,

RenderDoc may use both 3Dmigoto and HLSL-Decompiler's code to decompile DXBC.

https://github.com/YYadorigi/HLSL-Decompiler

I think the DecompileHLSL.cpp in 3Dmigoto is not reliable in some case, will try to dump as bin and decompile it with YYadorigi's HLSL-Decompiler, so the question comes, can 3Dmigoto correctly translate SM5.1 HLSL to DXBC?

I have seen SpectrumQT use d3dcompiler47.dll in WWMI project, is this means the old d3dcompiler46.dll is not enough in moredn UE5 fames?

Or is that means 3Dmigoto is limited in these parts? I'm lazy to test.

I don't know, it maybe doesn't matter, but in case this information is useful in future, write it down here.

And if YYadorigi's HLSL-Decompiler can works perfect ,is this project even worth to be exists ???




