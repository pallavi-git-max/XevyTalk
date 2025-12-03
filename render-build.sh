#!/bin/bash
# Render build script for backend

echo "Installing server dependencies..."
cd server
npm install
cd ..

echo "Build complete!"
