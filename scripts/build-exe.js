const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const esbuild = require('esbuild');

async function buildExe() {
  console.log('\n=============================================================');
  console.log(' BUILDING STANDALONE WINDOWS .EXE DESKTOP APPLICATION');
  console.log('=============================================================\n');

  const rootDir = __dirname ? path.resolve(__dirname, '..') : process.cwd();
  const distDir = path.join(rootDir, 'dist');

  if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir, { recursive: true });
  }

  // 1. Read ui.html and prepare inlined bundle
  console.log('1. Bundling desktop application with inlined minimal UI...');
  const bundlePath = path.join(distDir, 'desktop-bundle.cjs');

  await esbuild.build({
    entryPoints: [path.join(rootDir, 'desktop-app/src/server.ts')],
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    outfile: bundlePath,
    loader: { '.html': 'text' },
    external: ['pg'], // pg is optional for in-memory desktop mode
    define: {
      'import.meta.url': '""'
    }
  });

  console.log('✓ Successfully created bundle:', bundlePath);

  // 2. Prepare SEA config
  console.log('\n2. Generating Single Executable Application preparation blob...');
  const seaConfigPath = path.join(distDir, 'sea-config.json');
  const seaBlobPath = path.join(distDir, 'sea-prep.blob');

  fs.writeFileSync(
    seaConfigPath,
    JSON.stringify(
      {
        main: bundlePath,
        output: seaBlobPath,
        disableExperimentalSEAWarning: true
      },
      null,
      2
    )
  );

  cp.execSync(`node --experimental-sea-config "${seaConfigPath}"`, { stdio: 'inherit' });
  console.log('✓ Generated SEA blob:', seaBlobPath);

  // 3. Create role-audit-engine.exe
  const targetExe = path.join(rootDir, 'role-audit-engine.exe');
  console.log('\n3. Creating base executable binary from Node runtime:', targetExe);
  fs.copyFileSync(process.execPath, targetExe);

  // 4. Inject blob with postject
  console.log('\n4. Injecting SEA blob into Windows executable using postject...');
  const postjectCli = path.join(rootDir, 'node_modules/postject/dist/cli.js');
  const injectCmd = `node "${postjectCli}" "${targetExe}" NODE_SEA_BLOB "${seaBlobPath}" --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 --overwrite`;

  cp.execSync(injectCmd, { stdio: 'inherit' });
  console.log('✓ Injected application into:', targetExe);

  // 5. Copy to user Desktop folder if available
  const desktopFolder = 'C:\\Users\\arnav pandey\\OneDrive\\Desktop';
  const desktopExe = path.join(desktopFolder, 'role-audit-engine.exe');
  try {
    if (fs.existsSync(desktopFolder)) {
      fs.copyFileSync(targetExe, desktopExe);
      console.log('\n5. Copied standalone executable to Desktop:');
      console.log('   ->', desktopExe);
    }
  } catch (err) {
    console.log('Note: Could not copy directly to Desktop folder, but exe is ready at:', targetExe);
  }

  const stat = fs.statSync(targetExe);
  const sizeMb = (stat.size / (1024 * 1024)).toFixed(1);

  console.log('\n=============================================================');
  console.log(` BUILD SUCCESSFUL! Standalone .exe created (${sizeMb} MB)`);
  console.log(` Executable Path: ${targetExe}`);
  if (fs.existsSync(desktopExe)) {
    console.log(` Desktop Shortcut / Executable: ${desktopExe}`);
  }
  console.log(' Double-click the .exe file anytime to launch the minimal desktop app!');
  console.log('=============================================================\n');
}

buildExe().catch((err) => {
  console.error('Build failed:', err);
  process.exit(1);
});
