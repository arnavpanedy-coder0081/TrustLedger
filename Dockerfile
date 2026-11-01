FROM node:22-alpine

WORKDIR /usr/src/app

COPY package*.json ./
COPY tsconfig.json ./
COPY tsconfig.build.json ./
COPY packages ./packages
COPY cli ./cli
COPY examples ./examples
COPY migrations ./migrations

RUN npm ci
RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start:example"]
