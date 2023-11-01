import { getUserByUsername } from '../../db/users.js'
import bcrypt from "bcrypt"
import { generateTokens, sendRefreshToken } from '../../utils/jwt.js'
import { userTransformer } from '~/server/transformers/user.js'
import { createRefreshToken } from '~/server/db/refreshTokens.js'
import { sendError } from "h3"

export default defineEventHandler(async (event) => {
    const body = await readBody(event)
    const { username, password } = body

    if (!username || !password) {
        return sendError(event, createError({
            statusCode: 400,
            statusMessage: 'Invalid params'
        }))
    }

    /* Is the user registered */
    const user = await getUserByUsername(username)

    if (!user) {
        return sendError(event, createError({
            statusCode: 400,
            statusMessage: 'Username or password is invalid'
        }))
    }

    /* Compare passwords */
    const doesThePasswordMatch = await bcrypt.compare(password, user.password)

    if (!doesThePasswordMatch) {
        return sendError(event, createError({
            statusCode: 400,
            statusMessage: 'Username or password is invalid'
        }))
    }

    /* Generate tokens */
    /* Access token */
    /* Refresh token */
    const { accessToken, refreshToken } = generateTokens(user)

    /* Save it inside db */
    await createRefreshToken({
        token: refreshToken,
        userId: user.id
    })

    /* Add http only cookie */
    sendRefreshToken(event, refreshToken)

    return {
        accessToken: accessToken, user: userTransformer(user)
    }

})