// generateHash12Rounds.js
const bcrypt = require('bcrypt');

async function checkAndGenerate() {
  // Primero, verifiquemos qué contraseña corresponde a ese hash
  const existingHash = '$2a$12$XovTOF4pkAY7RgW2VabJceEgNQPk.TjDmWxbwno5fWaL2wgHmBwjy';
  
  // Probar algunas contraseñas comunes
  const passwords = ['admin', 'admin123', 'password', 'Admin123', 'admin@123'];
  
  console.log('🔍 Probando contraseñas con el hash existente:');
  for (const pwd of passwords) {
    const matches = await bcrypt.compare(pwd, existingHash);
    if (matches) {
      console.log(`✅ ENCONTRADA: "${pwd}" coincide con el hash!`);
    }
  }
  
  // Generar nuevo hash para admin123 con 12 rounds
  console.log('\n📝 Generando nuevos hashes con 12 rounds:');
  const adminHash = await bcrypt.hash('admin123', 12);
  const serviceHash = await bcrypt.hash('service123', 12);
  
  console.log('admin (admin123):', adminHash);
  console.log('core-services (service123):', serviceHash);
}

checkAndGenerate();