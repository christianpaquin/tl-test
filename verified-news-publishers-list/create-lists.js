#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const outputFile = 'verified-news-publishers-list';
const pemListFile = `${outputFile}.pem`;
const jsonListFile = `${outputFile}.json`;

// JSON list (with no entities)
const jsonList = {
    version: "0.1",
    name: "IPTC - Verified Publishers",
    download_url: "https://www.iptc.org/verified-news-publishers-list/verified-news-publishers-list.json",
    description: "International Press Telecommunications Council (IPTC) - Origin Verified News Publishers List",
    website: "https://iptc.org/verified-news-publishers-list/",
    logo_icon: "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c3ZnIGlkPSJMYXllcl8yIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxNiAxNiI+PGRlZnM+PHN0eWxlPi5jbHMtMXtmaWxsOiM0MThiODM7fS5jbHMtMSwuY2xzLTIsLmNscy0zLC5jbHMtNHtzdHJva2Utd2lkdGg6MHB4O30uY2xzLTJ7ZmlsbDojYTUzY2JlO30uY2xzLTN7ZmlsbDojNWE5M2YzO30uY2xzLTR7ZmlsbDojZmZmO308L3N0eWxlPjwvZGVmcz48ZyBpZD0iT1ZQIj48cGF0aCBjbGFzcz0iY2xzLTIiIGQ9Ik04LDE2YzQuNDIsMCw4LTMuNTgsOC04LDAtMi4yLS44OS00LjE4LTIuMzItNS42M0wyLjg5LDE0LjE1YzEuMzksMS4xNSwzLjE3LDEuODUsNS4xMSwxLjg1WiIvPjxwYXRoIGNsYXNzPSJjbHMtMSIgZD0iTTEzLjgyLDIuNTFjLTEuNDYtMS41NS0zLjUzLTIuNTEtNS44Mi0yLjUxQzQuNzksMCwyLjAzLDEuODkuNzUsNC42MWw2LjA2LDUuNTUsNy4wMS03LjY1WiIvPjxwYXRoIGNsYXNzPSJjbHMtMyIgZD0iTS44Myw0LjQ1Yy0uNTMsMS4wNy0uODMsMi4yNy0uODMsMy41NSwwLDIuNTUsMS4xOSw0LjgxLDMuMDQsNi4yOGwzLjg5LTQuMjRMLjgzLDQuNDVaIi8+PHBvbHlnb24gaWQ9IkNoZWNrbWFyayIgY2xhc3M9ImNscy00IiBwb2ludHM9IjYuODYgMTEuMjggMy45NCA4LjM2IDUuMDQgNy4yNSA2LjgxIDkuMDEgMTAuNTUgNC45MyAxMS43IDUuOTkgNi44NiAxMS4yOCIvPjwvZz48L3N2Zz4=",
    last_updated: new Date().toISOString(),
    entities: []
}

// get the certificate info from a cert file using openssl
// TODO: extract that to a different file to be used in other scripts
// TODO: add more cert validation (to make sure it complies with C2PA profile)
function getCertInfo(certPath) {
    const cmd = `openssl x509 -in ${certPath} -text -noout`;

    try {
        const output = execSync(cmd, { encoding: 'utf8' });

        const subjectMatch = output.match(/Subject: (.+)/);
        const issuerMatch = output.match(/Issuer: (.+)/);
        const notBeforeMatch = output.match(/Not Before: (.+)/);
        const notAfterMatch = output.match(/Not After : (.+)/);
        const serialMatch = output.match(/Serial Number:\s+([0-9A-Fa-f:\s]+)/);
        const pubkeyAlgMatch = output.match(/Public Key Algorithm: (.+)/);
        const keyExtMatch = output.match(/X509v3 Key Usage:[\s\S]*?\n\s+(.+)/);
        const extKeyUsageMatch = output.match(/X509v3 Extended Key Usage:[\s\S]*?\n\s+(.+)/);
        const basicConstraintsMatch = output.match(/X509v3 Basic Constraints:[\s\S]*?\n\s+(.+)/);

        const info = {
            subject: subjectMatch ? subjectMatch[1].trim() : undefined,
            issuer: issuerMatch ? issuerMatch[1].trim() : undefined,
            notBefore: notBeforeMatch ? notBeforeMatch[1].trim() : undefined,
            notAfter: notAfterMatch ? notAfterMatch[1].trim() : undefined,
            serial: serialMatch ? serialMatch[1].replace(/[\s:]/g, '').trim() : undefined,
            publicKeyAlgorithm: pubkeyAlgMatch ? pubkeyAlgMatch[1].trim() : undefined,
            keyUsage: keyExtMatch ? keyExtMatch[1].split(',').map(usage => usage.trim()) : [],
            keyUsageCritical: keyExtMatch ? keyExtMatch[0].includes('critical') : false,
            extendedKeyUsage: extKeyUsageMatch ? extKeyUsageMatch[1].trim() : undefined,
            basicConstraints: basicConstraintsMatch ? basicConstraintsMatch[1].trim() : undefined,
            basicConstraintsCritical: basicConstraintsMatch ? basicConstraintsMatch[0].includes('critical') : false
        };

        return info;
    } catch (error) {
        throw new Error(`Error executing openssl: ${error.message}`);
    }
}

// get all directories in the root directory
function getDirectories(rootDir) {
    return fs.readdirSync(rootDir).filter(file => {
        return fs.statSync(path.join(rootDir, file)).isDirectory();
    });
}

// get all PEM files in a given directory
function getPemFiles(dir) {
    return fs.readdirSync(dir).filter(file => file.endsWith('.pem')).map(file => path.join(dir, file));
}

// parse the per-publisher entity file
function parseEntityFile(file) {
    const entity = JSON.parse(fs.readFileSync(file, 'utf-8'));
    // make sure that the entity only contains the necessary fields
    const requiredFields = ['display_name', 'contact', 'isCA'];
    Object.keys(entity).forEach(key => {
        if (!requiredFields.includes(key)) {
            delete entity[key];
        }
    });
    if ((entity.display_name === undefined && typeof entity.display_name !== 'string') ||
        (entity.contact === undefined && typeof entity.contact !== 'string') ||
        (entity.isCA === undefined && typeof entity.isCA !== 'boolean')) {
        throw new Error(`The entity file ${file} is not in the correct format`);
    }

    // add the jwks
    entity.jwks = {
        keys: []
    };
    return entity;
}

// convert a PEM file to a x5c
function pemToX5c(pem) {
    return pem.replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\n/g, '');
}

// get the JWK key type from a public key algorithm 
// c.f. https://www.rfc-editor.org/rfc/rfc7518.html#section-6.1
function getKty(publicKeyAlgorithm) {
    const alg = publicKeyAlgorithm.toLowerCase();
    if (alg.includes('rsa')) {
        return 'RSA';
    } else if (alg.includes('ec')) {
        return 'EC';
    } else if (alg.includes('25519')) {
        return 'oct';
    } else {
        throw new Error(`Unsupported public key algorithm: ${publicKeyAlgorithm}`);
    }
}

// create the PEM and JSON lists
function createLists() {
    const rootDir = path.join(__dirname, 'Publishers');
    const directories = getDirectories(rootDir);

    let concatenatedPemFiles = '';
    directories.forEach(dir => {
        // read the entity file
        const entity = parseEntityFile(path.join(rootDir, dir, 'entity.json'));

        // get the PEM files for the entity
        const pemFiles = getPemFiles(path.join(rootDir, dir));
        pemFiles.forEach(file => {
            const certInfo = getCertInfo(file);
            console.log(`Parsing ${file}\n`, certInfo);
            // read the PEM file
            const pem = fs.readFileSync(file, 'utf8');
            concatenatedPemFiles += pem + '\n';
            // TODO: should I always put a newline? Concatenated PEM files can have 
            // empty lines between them. This at least makes sure that there a separation
            // between the PEM files.

            // convert the PEM file to a x5c
            const x5c = pemToX5c(pem);

            entity.jwks.keys.push({
                kty: getKty(certInfo.publicKeyAlgorithm),
                x5c: [x5c]
            });
        });

        jsonList.entities.push(entity);
    });

    fs.writeFileSync(pemListFile, concatenatedPemFiles, 'utf8');
    console.log(`The PEM list has been created into ${pemListFile}`);

    fs.writeFileSync(jsonListFile, JSON.stringify(jsonList, null, 2), 'utf8');
    console.log(`The JSON list has been created into ${jsonListFile}`);
}

createLists();
