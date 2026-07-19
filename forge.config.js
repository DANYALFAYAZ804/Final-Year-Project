const { FusesPlugin } = require('@electron-forge/plugin-fuses');
const { FuseV1Options, FuseVersion } = require('@electron/fuses');
const path = require('path');

module.exports = {
  packagerConfig: {
    asar: true,
    icon: path.join(__dirname, 'src', 'assets', 'Trust-Flow-logo'), // .ico added automatically on win32
    // Copies src/assets into the packaged app's resources folder
    // (resources/assets on win32/linux, Contents/Resources/assets on mac)
    // so main.js can load the icon at runtime via process.resourcesPath,
    // since files under src/ aren't otherwise guaranteed to land in a
    // predictable spot after the Vite build.
    extraResource: [
      'src/assets',
    ],
    // Exclude dev-only / backend source from the packaged app now that
    // the ML backend is deployed remotely on Railway and no longer
    // spawned locally by main.js.
    ignore: [
      /^\/backend($|\/)/,      // Python ML backend source, model.pkl, venv, etc.
      /^\/\.git($|\/)/,
      /^\/\.vscode($|\/)/,
      /^\/vite\.main\.config\.mjs$/,
      /^\/vite\.preload\.config\.mjs$/,
      /^\/vite\.renderer\.config\.mjs$/,
      /^\/forge\.config\.js$/,
      /(^|\/)\.env$/,
      /(^|\/)README\.md$/,
    ],
  },
  rebuildConfig: {},
  makers: [
    {
      // Wizard-style Windows installer (.msi): license page, choose install
      // folder, Next/Next/Finish — like VS Code. Requires the WiX Toolset v3
      // (candle.exe / light.exe) to be installed on the build machine, and
      // only builds on Windows.
      name: '@electron-forge/maker-wix',
      config: {
        language: 1033,
        manufacturer: 'Danyal Fayaz',
        appUserModelId: 'com.danyalfayaz.trustflow',
        ui: {
          chooseDirectory: true,      // lets the user pick install location
        },
        // WiX needs a license in .rtf format for the license-agreement page
        licenseFile: path.join(__dirname, 'LICENSE.rtf'),
        // Explicit icon avoids electron-wix-msi trying (and failing) to
        // auto-extract one from the built .exe via an optional dependency
        // that isn't installed (@bitdisaster/exe-icon-extractor).
        icon: path.join(__dirname, 'src', 'assets', 'Trust-Flow-logo.ico'),
      },
    },
    {
      name: '@electron-forge/maker-zip',
      platforms: ['darwin'],
    },
    {
      name: '@electron-forge/maker-deb',
      config: {},
    },
    {
      name: '@electron-forge/maker-rpm',
      config: {},
    },
  ],
  plugins: [
    {
      name: '@electron-forge/plugin-vite',
      config: {
        build: [
          {
            entry: 'src/main.js',
            config: 'vite.main.config.mjs',
            target: 'main',
          },
          {
            entry: 'src/preload.js',
            config: 'vite.preload.config.mjs',
            target: 'preload',
          },
        ],
        renderer: [
          {
            name: 'main_window',
            config: 'vite.renderer.config.mjs',
          },
        ],
      },
    },
    new FusesPlugin({
      version: FuseVersion.V1,
      [FuseV1Options.RunAsNode]: false,
      [FuseV1Options.EnableCookieEncryption]: true,
      [FuseV1Options.EnableNodeOptionsEnvironmentVariable]: false,
      [FuseV1Options.EnableNodeCliInspectArguments]: false,
      [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]: true,
      [FuseV1Options.OnlyLoadAppFromAsar]: true,
    }),
  ],
};