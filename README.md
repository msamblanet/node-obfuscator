# Node Typescript Template

This repository is part of a collection of my personal node.js libraries and templates.  I am making them available to the public - feel free to offer suggestions, report issues, or make PRs via GitHub.

This project is a template node.js project for use with server-side typescript.  It provides for unit testing, typescript compilation, and debugging.  Configuration for debugging in Visual Studio Code is provided.

## Usage

- Create a new GitHub project using the ```Use this template``` in Github
    - If not using github, download or clone the files into your own repository
- Review and update:
    - [package.json](./package.json)
    - [README.md](./README.md)
    - [TODO.md](./TODO.md)
    - [HISTORY.md](./HISTORY.md)
    - [LICENSE](./LICENSE)
- Implement your library in [src/index.ts](./src/index.ts)
- Implement your main code in [src/main.ts](./src/main.ts)
- Define any necessary 3rd party library typescript definitions in [src/@types](./src/@types)
    - Delete [src/@types](./src/@types/example-module) once no longer needed
- Implement your unit tests in [test/](./test)
    - Unit test files should be named ```*.test.ts```
    - Delete [test/example.test.ts](./test/example.test.ts) once no longer needed

## Features

- Preconfigured package.json for making both CJS and MJS style code
- Integration with [Jest](https://jestjs.io/) for unit testing and code coverage reporting
- Configuration with Visual Studio Code to provide debugging launch commands
- Integration with eslint

## npm run scripts available

- ```npm run dev``` - Runs ```src/main.ts``` script locally
- ```npm run debug``` - Runs ```src/main.ts``` script locally with the JS inspector enabled
- ```npm run nodemon``` - Runs ```src/main.ts``` script locally via nodemon (to restart on file changes)
    - ```npm run nodemon:debug``` - Same as nodemon but has the JS inspector enabled
- ```npm run test``` - Runs all of the Jest unit tests
    - ```npm run test:debug``` - Same but has the JS inspector enabled
    - ```npm run test:watch``` - Runs all of the Jest unit tests in watch mode (to retest on changes)
    - ```npm run test:watch:debug``` - Same but has the JS inspector enabled
- ```npm run lint``` - Runs eslint
    - ```npm run lint:fix``` - Runs eslint with the fix option
- ```npm run build``` - Performs a build:clean and build:gen to build the code
    - ```npm run build:clean``` - Deletes the dist folder
    - ```npm run build:check``` - Runs tsc without output to verify the code
    - ```npm run build:gen``` - Runs tsc to compile the typescript
- prepack - This is executed just before npm packages for release.  It runs a lint, build:check, and build to generate the library for packaging.
- ```lib:check``` - Reports on updated dependencies WITHOUT installing any
- ```lib:update:patch``` - Update and install all available patch level updates
- ```lib:update:minor``` - Update and install all available patch and minor level updates
- ```lib:update:latest``` - Update and install all available dependencies to the latest version (MAY INCLUDE BREAKING CHANGES)
- ```lib:update:doctor``` - Run NCU in "doctor" mode to update all libraries - uses unit tests to see if any individual update breaks the system
    - For more info, run ```npx ncu --doctor```

## VSCode Debug Actions

- ```Unit Tests: All``` - Runs all unit tests in the debugger
- ```Unit Tests: Watch``` - Runs all the unit tests in watch mode in the debugger
- ```Unit Tests: Current File``` - Runs the currently open file as a unit test in the debugger
- ```Debug: Current File``` - Runs the current file as application code in the debugger
- ```Debug: src/main.ts``` - Runs the main entry point in the debugger
- ```Debug: Attach to 5858``` - Ataches the IDE to the default JS inspector port locally
